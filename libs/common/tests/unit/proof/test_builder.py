"""Unit tests for common.proof.builder."""

from __future__ import annotations

import base64
import json
import uuid

import pytest

from common.crypto.did_key import generate_did_key
from common.proof.builder import build_proof, build_req_binding
from common.proof.hash_utils import EMPTY_HASH, hash_bytes, hash_query
from common.proof.models import MAX_PROOF_TTL, PROOF_TYP, ProofClaims, ReqBinding


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
    return build_req_binding(
        method="GET",
        path="/api/v1/health",
    )


# ---------------------------------------------------------------------------
# build_req_binding
# ---------------------------------------------------------------------------


class TestBuildReqBinding:
    def test_returns_req_binding(self) -> None:
        rb = build_req_binding(method="GET", path="/api/v1/test")
        assert isinstance(rb, ReqBinding)

    def test_method_is_upper_cased(self) -> None:
        rb = build_req_binding(method="post", path="/endpoint")
        assert rb.method == "POST"

    def test_no_query_gives_empty_hash(self) -> None:
        rb = build_req_binding(method="GET", path="/path")
        assert rb.query_hash == EMPTY_HASH

    def test_query_is_hashed(self) -> None:
        rb = build_req_binding(method="GET", path="/path", raw_query="foo=bar")
        assert rb.query_hash == hash_query("foo=bar")

    def test_no_body_gives_empty_hash(self) -> None:
        rb = build_req_binding(method="GET", path="/path")
        assert rb.body_hash == EMPTY_HASH

    def test_body_is_hashed(self) -> None:
        body = b'{"key":"val"}'
        rb = build_req_binding(method="POST", path="/data", body=body)
        assert rb.body_hash == hash_bytes(body)

    def test_content_type_is_normalized(self) -> None:
        rb = build_req_binding(
            method="POST",
            path="/upload",
            content_type="Application/JSON; charset=utf-8",
        )
        assert rb.content_type == "application/json"

    def test_no_content_type_is_none(self) -> None:
        rb = build_req_binding(method="GET", path="/data")
        assert rb.content_type is None


# ---------------------------------------------------------------------------
# build_proof
# ---------------------------------------------------------------------------


class TestBuildProof:
    def test_returns_compact_jws(self, consumer_kp, producer_kp, simple_req) -> None:
        proof = build_proof(
            consumer_kp.private_key(),
            consumer_did=consumer_kp.did,
            kid=consumer_kp.verification_method_id,
            producer_did=producer_kp.did,
            env="test",
            req=simple_req,
        )
        assert proof.count(".") == 2

    def test_typ_header_is_sentinel_proof_jwt(self, consumer_kp, producer_kp, simple_req) -> None:
        proof = build_proof(
            consumer_kp.private_key(),
            consumer_did=consumer_kp.did,
            kid=consumer_kp.verification_method_id,
            producer_did=producer_kp.did,
            env="dev",
            req=simple_req,
        )
        header_b64 = proof.split(".")[0]
        header = json.loads(base64.urlsafe_b64decode(header_b64 + "=="))
        assert header.get("typ") == PROOF_TYP

    def test_kid_in_header(self, consumer_kp, producer_kp, simple_req) -> None:
        proof = build_proof(
            consumer_kp.private_key(),
            consumer_did=consumer_kp.did,
            kid=consumer_kp.verification_method_id,
            producer_did=producer_kp.did,
            env="dev",
            req=simple_req,
        )
        header = json.loads(base64.urlsafe_b64decode(proof.split(".")[0] + "=="))
        assert header.get("kid") == consumer_kp.verification_method_id

    def test_unique_jti_each_call(self, consumer_kp, producer_kp, simple_req) -> None:
        jtis = set()
        for _ in range(10):
            p = build_proof(
                consumer_kp.private_key(),
                consumer_did=consumer_kp.did,
                kid=consumer_kp.verification_method_id,
                producer_did=producer_kp.did,
                env="dev",
                req=simple_req,
            )
            payload_raw = base64.urlsafe_b64decode(p.split(".")[1] + "==")
            jtis.add(json.loads(payload_raw)["jti"])
        assert len(jtis) == 10

    def test_jti_is_uuid4(self, consumer_kp, producer_kp, simple_req) -> None:
        proof = build_proof(
            consumer_kp.private_key(),
            consumer_did=consumer_kp.did,
            kid=consumer_kp.verification_method_id,
            producer_did=producer_kp.did,
            env="dev",
            req=simple_req,
        )
        payload = json.loads(base64.urlsafe_b64decode(proof.split(".")[1] + "=="))
        # Should parse cleanly as UUID
        parsed = uuid.UUID(payload["jti"])
        assert parsed.version == 4

    def test_claims_match_inputs(self, consumer_kp, producer_kp) -> None:
        req = build_req_binding(
            method="POST",
            path="/api/v1/data",
            body=b'{"test": true}',
            content_type="application/json",
        )
        proof = build_proof(
            consumer_kp.private_key(),
            consumer_did=consumer_kp.did,
            kid=consumer_kp.verification_method_id,
            producer_did=producer_kp.did,
            env="prod",
            req=req,
        )
        payload = json.loads(base64.urlsafe_b64decode(proof.split(".")[1] + "=="))
        assert payload["iss"] == consumer_kp.did
        assert payload["aud"] == producer_kp.did
        assert payload["env"] == "prod"
        assert payload["req"]["method"] == "POST"
        assert payload["req"]["path"] == "/api/v1/data"

    def test_exp_equals_iat_plus_ttl(self, consumer_kp, producer_kp, simple_req) -> None:
        proof = build_proof(
            consumer_kp.private_key(),
            consumer_did=consumer_kp.did,
            kid=consumer_kp.verification_method_id,
            producer_did=producer_kp.did,
            env="dev",
            req=simple_req,
            ttl=10,
        )
        payload = json.loads(base64.urlsafe_b64decode(proof.split(".")[1] + "=="))
        assert payload["exp"] - payload["iat"] == 10

    def test_zero_ttl_raises(self, consumer_kp, producer_kp, simple_req) -> None:
        with pytest.raises(ValueError, match="ttl"):
            build_proof(
                consumer_kp.private_key(),
                consumer_did=consumer_kp.did,
                kid=consumer_kp.verification_method_id,
                producer_did=producer_kp.did,
                env="dev",
                req=simple_req,
                ttl=0,
            )

    def test_ttl_exceeds_max_raises(self, consumer_kp, producer_kp, simple_req) -> None:
        with pytest.raises(ValueError, match="ttl"):
            build_proof(
                consumer_kp.private_key(),
                consumer_did=consumer_kp.did,
                kid=consumer_kp.verification_method_id,
                producer_did=producer_kp.did,
                env="dev",
                req=simple_req,
                ttl=MAX_PROOF_TTL + 1,
            )

    def test_nonce_included_when_provided(self, consumer_kp, producer_kp, simple_req) -> None:
        proof = build_proof(
            consumer_kp.private_key(),
            consumer_did=consumer_kp.did,
            kid=consumer_kp.verification_method_id,
            producer_did=producer_kp.did,
            env="dev",
            req=simple_req,
            nonce="test-nonce-value",
        )
        payload = json.loads(base64.urlsafe_b64decode(proof.split(".")[1] + "=="))
        assert payload.get("nonce") == "test-nonce-value"

    def test_no_nonce_absent_from_payload(self, consumer_kp, producer_kp, simple_req) -> None:
        proof = build_proof(
            consumer_kp.private_key(),
            consumer_did=consumer_kp.did,
            kid=consumer_kp.verification_method_id,
            producer_did=producer_kp.did,
            env="dev",
            req=simple_req,
        )
        payload = json.loads(base64.urlsafe_b64decode(proof.split(".")[1] + "=="))
        assert "nonce" not in payload

    def test_trace_id_included_when_provided(self, consumer_kp, producer_kp, simple_req) -> None:
        proof = build_proof(
            consumer_kp.private_key(),
            consumer_did=consumer_kp.did,
            kid=consumer_kp.verification_method_id,
            producer_did=producer_kp.did,
            env="dev",
            req=simple_req,
            trace_id="4bf92f3577b34da6a3ce929d0e0e4736",
        )
        payload = json.loads(base64.urlsafe_b64decode(proof.split(".")[1] + "=="))
        assert payload.get("trace_id") == "4bf92f3577b34da6a3ce929d0e0e4736"
