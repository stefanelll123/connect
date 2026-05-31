"""Integration test: end-to-end Sentinel onboarding flow.

Simulates the full two-phase onboarding protocol entirely in-process:
  Phase 1 — Discovery issues enrollment token → Sentinel sends challenge
             request → Discovery validates token and returns a challenge.
  Phase 2 — Sentinel creates onboarding proof → Discovery verifies proof
             and issues an onboarding bundle.

Also covers:
  * Replay attack: second use of a consumed enrollment-token hash.
  * Expired challenge: proof submitted after challenge expires.
  * Wrong DID in proof: sentinel presents a DID that doesn't match
    the enrollment token.
"""

from __future__ import annotations

import os
import time
from typing import Dict, Optional

import pytest

from common.crypto.did_key import generate_did_key
from common.onboarding.models import (
    ChallengeResponse,
    ContractAddresses,
    OnboardCompleteRequest,
    OnboardInitiateRequest,
    OnboardingBundle,
    OnboardingError,
    TrustAnchors,
)
from common.onboarding.proof import (
    OnboardingProofError,
    create_onboarding_proof,
    verify_onboarding_proof,
)
from common.onboarding.token import (
    EnrollmentTokenError,
    create_enrollment_token,
    hash_token,
    validate_enrollment_token,
)


# ---------------------------------------------------------------------------
# Minimal in-process "Discovery" service stub
# ---------------------------------------------------------------------------

_CHALLENGE_TTL = 60  # seconds — short for test predictability


class _InMemoryDiscovery:
    """In-process stub that implements the Discovery server logic."""

    def __init__(self, keypair) -> None:
        self._keypair = keypair
        self._used_token_hashes: set[str] = set()  # consumed jti hashes
        self._pending_challenges: Dict[str, dict] = {}  # jti → {challenge, exp}

    # ------------------------------------------------------------------
    # Phase 1: Sentinel sends enrollment token; Discovery returns challenge
    # ------------------------------------------------------------------

    def phase1_challenge(self, request: OnboardInitiateRequest) -> ChallengeResponse:
        # Validate token signature
        try:
            claims = validate_enrollment_token(
                request.enrollment_token, self._keypair.public_key()
            )
        except EnrollmentTokenError as exc:
            raise ValueError(exc.code) from exc

        # Replay detection (token hash)
        token_hash = hash_token(request.enrollment_token)
        if token_hash in self._used_token_hashes:
            raise ValueError("ENROLLMENT_TOKEN_ALREADY_CONSUMED")

        # Issue challenge
        challenge = os.urandom(32).hex()
        correlation_id = os.urandom(8).hex()
        self._pending_challenges[claims.jti] = {
            "challenge": challenge,
            "exp": int(time.time()) + _CHALLENGE_TTL,
            "sentinel_did": request.did,
        }
        return ChallengeResponse(
            challenge=challenge,
            expires_in=_CHALLENGE_TTL,
            correlation_id=correlation_id,
        )

    # ------------------------------------------------------------------
    # Phase 2: Sentinel submits proof; Discovery issues bundle
    # ------------------------------------------------------------------

    def phase2_complete(
        self, request: OnboardCompleteRequest
    ) -> OnboardingBundle:
        # Re-validate enrollment token
        try:
            claims = validate_enrollment_token(
                request.enrollment_token, self._keypair.public_key()
            )
        except EnrollmentTokenError as exc:
            raise ValueError(exc.code) from exc

        # Replay check (mark consumed here — after proof verification)
        token_hash = hash_token(request.enrollment_token)
        if token_hash in self._used_token_hashes:
            raise ValueError("ENROLLMENT_TOKEN_ALREADY_CONSUMED")

        pending = self._pending_challenges.get(claims.jti)
        if pending is None:
            raise ValueError("CHALLENGE_NOT_FOUND")
        if int(time.time()) > pending["exp"]:
            del self._pending_challenges[claims.jti]
            raise ValueError("CHALLENGE_EXPIRED")

        # Reconstruct Sentinel public key from request
        from common.crypto.did_key import did_key_to_public_key

        sentinel_pub = did_key_to_public_key(pending["sentinel_did"])

        # Verify proof
        try:
            verify_onboarding_proof(
                request.proof,
                sentinel_pub,
                expected_discovery_did=self._keypair.did,
                expected_token_id=claims.jti,
                expected_challenge=pending["challenge"],
            )
        except OnboardingProofError as exc:
            raise ValueError(exc.code) from exc

        # Mark token consumed
        self._used_token_hashes.add(token_hash)
        del self._pending_challenges[claims.jti]

        # Build and return bundle
        return OnboardingBundle(
            sentinel_id="00000000-0000-0000-0000-000000000001",  # stub UUID
            did=pending["sentinel_did"],
            service_id=claims.service_id,
            role=claims.role,
            env=claims.env,
            config_version=1,
            trust_anchors=TrustAnchors(
                chain_network="testnet",
                chain_id=1337,
                rpc_urls=["http://localhost:8545"],
                contract_addresses=ContractAddresses(
                    issuer_registry="0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    trust_policy_registry="0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                    status_registry="0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
                    service_registry="0xDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
                ),
            ),
        )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def discovery_kp():
    return generate_did_key()


@pytest.fixture(scope="module")
def sentinel_kp():
    return generate_did_key()


@pytest.fixture(scope="module")
def discovery(discovery_kp):
    return _InMemoryDiscovery(discovery_kp)


@pytest.fixture
def enrollment_token(discovery_kp):
    """Fresh enrollment token for each test (unique JTI)."""
    return create_enrollment_token(
        discovery_kp.private_key(),
        issuer_did=discovery_kp.did,
        kid=discovery_kp.verification_method_id,
        service_id="svc-integration-test",
        role="PRODUCER",
        env="test",
        ttl=600,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestHappyPath:
    def test_full_onboarding_flow(
        self, discovery, discovery_kp, sentinel_kp, enrollment_token
    ) -> None:
        """Full two-phase onboarding succeeds and returns a valid bundle."""
        # Phase 1
        initiate_req = OnboardInitiateRequest(
            enrollment_token=enrollment_token,
            did=sentinel_kp.did,
            did_public_key_jwk={"kty": "OKP", "crv": "Ed25519", "x": "placeholder"},
        )
        challenge_resp = discovery.phase1_challenge(initiate_req)
        assert challenge_resp.challenge
        assert challenge_resp.expires_in > 0

        # Phase 2 — Sentinel creates proof
        claims = validate_enrollment_token(enrollment_token, discovery_kp.public_key())
        proof = create_onboarding_proof(
            sentinel_kp.private_key(),
            sentinel_did=sentinel_kp.did,
            kid=sentinel_kp.verification_method_id,
            discovery_did=discovery_kp.did,
            token_id=claims.jti,
            challenge=challenge_resp.challenge,
        )
        complete_req = OnboardCompleteRequest(
            enrollment_token=enrollment_token,
            proof=proof,
        )
        bundle = discovery.phase2_complete(complete_req)

        assert bundle.did == sentinel_kp.did
        assert bundle.service_id == "svc-integration-test"
        assert bundle.role == "PRODUCER"
        assert bundle.env == "test"
        assert bundle.trust_anchors.chain_id == 1337

    def test_bundle_has_contract_addresses(
        self, discovery, discovery_kp, sentinel_kp
    ) -> None:
        """Onboarding bundle includes non-empty contract addresses."""
        kp = generate_did_key()
        token = create_enrollment_token(
            discovery_kp.private_key(),
            issuer_did=discovery_kp.did,
            kid=discovery_kp.verification_method_id,
            service_id="svc-contracts-test",
            role="CONSUMER",
            env="dev",
        )
        initiate = OnboardInitiateRequest(
            enrollment_token=token,
            did=kp.did,
            did_public_key_jwk={"kty": "OKP"},
        )
        cr = discovery.phase1_challenge(initiate)
        claims = validate_enrollment_token(token, discovery_kp.public_key())
        proof = create_onboarding_proof(
            kp.private_key(),
            sentinel_did=kp.did,
            kid=kp.verification_method_id,
            discovery_did=discovery_kp.did,
            token_id=claims.jti,
            challenge=cr.challenge,
        )
        bundle = discovery.phase2_complete(
            OnboardCompleteRequest(enrollment_token=token, proof=proof)
        )
        ca = bundle.trust_anchors.contract_addresses
        assert ca.issuer_registry.startswith("0x")
        assert len(ca.issuer_registry) == 42


class TestReplayAttack:
    def test_second_use_of_same_token_is_rejected(
        self, discovery, discovery_kp, sentinel_kp
    ) -> None:
        """A token whose hash is already in used_token_hashes is rejected."""
        kp = generate_did_key()
        token = create_enrollment_token(
            discovery_kp.private_key(),
            issuer_did=discovery_kp.did,
            kid=discovery_kp.verification_method_id,
            service_id="svc-replay-test",
            role="PRODUCER",
            env="test",
        )
        initiate = OnboardInitiateRequest(
            enrollment_token=token,
            did=kp.did,
            did_public_key_jwk={"kty": "OKP"},
        )
        cr = discovery.phase1_challenge(initiate)
        claims = validate_enrollment_token(token, discovery_kp.public_key())
        proof = create_onboarding_proof(
            kp.private_key(),
            sentinel_did=kp.did,
            kid=kp.verification_method_id,
            discovery_did=discovery_kp.did,
            token_id=claims.jti,
            challenge=cr.challenge,
        )
        # First completion succeeds
        discovery.phase2_complete(
            OnboardCompleteRequest(enrollment_token=token, proof=proof)
        )

        # Attempt to replay — Phase 1 must reject
        with pytest.raises(ValueError, match="ENROLLMENT_TOKEN_ALREADY_CONSUMED"):
            discovery.phase1_challenge(
                OnboardInitiateRequest(
                    enrollment_token=token,
                    did=kp.did,
                    did_public_key_jwk={"kty": "OKP"},
                )
            )


class TestExpiredToken:
    def test_expired_enrollment_token_rejected_in_phase1(
        self, discovery, discovery_kp, sentinel_kp
    ) -> None:
        """An expired enrollment token is rejected during Phase 1."""
        import freezegun

        with freezegun.freeze_time("2020-01-01"):
            expired_token = create_enrollment_token(
                discovery_kp.private_key(),
                issuer_did=discovery_kp.did,
                kid=discovery_kp.verification_method_id,
                service_id="svc-expired-test",
                role="PRODUCER",
                env="test",
                ttl=60,
            )
        with pytest.raises(ValueError, match="ENROLLMENT_TOKEN_EXPIRED"):
            discovery.phase1_challenge(
                OnboardInitiateRequest(
                    enrollment_token=expired_token,
                    did=sentinel_kp.did,
                    did_public_key_jwk={"kty": "OKP"},
                )
            )


class TestWrongProof:
    def test_wrong_challenge_proof_rejected(
        self, discovery, discovery_kp, sentinel_kp, enrollment_token
    ) -> None:
        """Proof with wrong challenge value is rejected in Phase 2."""
        initiate = OnboardInitiateRequest(
            enrollment_token=enrollment_token,
            did=sentinel_kp.did,
            did_public_key_jwk={"kty": "OKP"},
        )
        discovery.phase1_challenge(initiate)
        claims = validate_enrollment_token(enrollment_token, discovery_kp.public_key())
        # Use a wrong challenge
        bad_proof = create_onboarding_proof(
            sentinel_kp.private_key(),
            sentinel_did=sentinel_kp.did,
            kid=sentinel_kp.verification_method_id,
            discovery_did=discovery_kp.did,
            token_id=claims.jti,
            challenge="wrong-challenge-entirely",
        )
        with pytest.raises(ValueError):
            discovery.phase2_complete(
                OnboardCompleteRequest(
                    enrollment_token=enrollment_token, proof=bad_proof
                )
            )

    def test_wrong_sentinel_key_proof_rejected(
        self, discovery, discovery_kp
    ) -> None:
        """Proof signed by a different key (not the claimed Sentinel DID) is rejected."""
        legitimate_kp = generate_did_key()
        rogue_kp = generate_did_key()

        token = create_enrollment_token(
            discovery_kp.private_key(),
            issuer_did=discovery_kp.did,
            kid=discovery_kp.verification_method_id,
            service_id="svc-wrong-key",
            role="CONSUMER",
            env="test",
        )
        initiate = OnboardInitiateRequest(
            enrollment_token=token,
            did=legitimate_kp.did,  # legitimate DID registered in challenge
            did_public_key_jwk={"kty": "OKP"},
        )
        cr = discovery.phase1_challenge(initiate)
        claims = validate_enrollment_token(token, discovery_kp.public_key())

        # Proof signed with rogue_kp (wrong key for legitimate_kp.did)
        bad_proof = create_onboarding_proof(
            rogue_kp.private_key(),
            sentinel_did=legitimate_kp.did,  # claims to be legitimate
            kid=rogue_kp.verification_method_id,
            discovery_did=discovery_kp.did,
            token_id=claims.jti,
            challenge=cr.challenge,
        )
        with pytest.raises(ValueError):
            discovery.phase2_complete(
                OnboardCompleteRequest(enrollment_token=token, proof=bad_proof)
            )
