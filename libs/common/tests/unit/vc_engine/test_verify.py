"""TASK-041 unit tests: VC/VP engine with adversarial vectors."""
from __future__ import annotations

import base64
import json
import os
import time
from typing import Optional
from unittest.mock import AsyncMock

import pytest


# ---------------------------------------------------------------------------
# Helpers: create test JWTs
# ---------------------------------------------------------------------------

def _gen_keypair():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.generate()
    return priv.private_bytes_raw(), priv.public_key().public_bytes_raw()


def _did_key(pub_bytes: bytes) -> str:
    from common.vc_engine.resolver import _b58_decode
    # Encode: multicodec 0xed01 + pub_bytes → base58btc → prepend 'z'
    b58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    data = bytes([0xed, 0x01]) + pub_bytes
    n = int.from_bytes(data, "big")
    result = []
    while n:
        n, r = divmod(n, 58)
        result.append(b58_alphabet[r])
    encoded = "".join(reversed(result))
    return f"did:key:z{encoded}"


def _make_vc_jwt(
    issuer_priv: bytes,
    issuer_pub: bytes,
    subject_did: str = "did:example:subject",
    cred_type: str = "VerifiableCredential",
    exp_offset: int = 3600,
    nbf_offset: int = -60,
    jti: str = "vc-jti-001",
    alg: str = "EdDSA",
    extra_claims: dict | None = None,
) -> str:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    issuer_did = _did_key(issuer_pub)
    now = int(time.time())
    payload = {
        "iss": issuer_did,
        "sub": subject_did,
        "jti": jti,
        "iat": now,
        "exp": now + exp_offset,
        "nbf": now + nbf_offset,
        "vc": {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential", cred_type],
            "credentialSubject": {"id": subject_did},
        },
    }
    if extra_claims:
        payload.update(extra_claims)

    header = {"alg": alg, "typ": "vc+jwt", "kid": f"{issuer_did}#key-1"}
    h = base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).rstrip(b"=").decode()
    signing_input = f"{h}.{p}".encode()

    if alg == "EdDSA":
        priv = Ed25519PrivateKey.from_private_bytes(issuer_priv)
        sig = base64.urlsafe_b64encode(priv.sign(signing_input)).rstrip(b"=").decode()
    else:
        sig = ""  # alg=none

    return f"{h}.{p}.{sig}"


# ---------------------------------------------------------------------------
# Test: DIDResolver
# ---------------------------------------------------------------------------

class TestDIDResolver:
    @pytest.mark.asyncio
    async def test_resolve_did_key_ed25519(self):
        from common.vc_engine.resolver import DIDResolver
        _, pub = _gen_keypair()
        did = _did_key(pub)
        resolver = DIDResolver()
        doc = await resolver.resolve(did)
        assert doc.id == did
        assert doc.first_verification_method is not None
        assert doc.first_verification_method.public_key_bytes == pub

    @pytest.mark.asyncio
    async def test_resolve_caches_result(self):
        from common.vc_engine.resolver import DIDResolver
        _, pub = _gen_keypair()
        did = _did_key(pub)
        resolver = DIDResolver()
        doc1 = await resolver.resolve(did)
        doc2 = await resolver.resolve(did)
        assert doc1 is doc2  # same object from cache

    @pytest.mark.asyncio
    async def test_resolve_unknown_did_method(self):
        from common.vc_engine.errors import VCError, VCErrorCode
        from common.vc_engine.resolver import DIDResolver
        resolver = DIDResolver()
        with pytest.raises(VCError) as exc_info:
            await resolver.resolve("did:unknown:xyz")
        assert exc_info.value.code == VCErrorCode.DID_UNRESOLVABLE

    @pytest.mark.asyncio
    async def test_resolve_malformed_did_key(self):
        from common.vc_engine.errors import VCError, VCErrorCode
        from common.vc_engine.resolver import DIDResolver
        resolver = DIDResolver()
        with pytest.raises(VCError) as exc_info:
            await resolver.resolve("did:key:zINVALID!!!!")
        assert exc_info.value.code == VCErrorCode.DID_UNRESOLVABLE


# ---------------------------------------------------------------------------
# Test: verify_vc
# ---------------------------------------------------------------------------

class TestVerifyVC:
    @pytest.mark.asyncio
    async def test_valid_vc_ed25519_round_trip(self):
        from common.vc_engine.resolver import DIDResolver
        from common.vc_engine.verifier import verify_vc
        priv, pub = _gen_keypair()
        did = _did_key(pub)
        vc_jwt = _make_vc_jwt(priv, pub)
        resolver = DIDResolver()
        result = await verify_vc(vc_jwt, {did}, resolver)
        assert result.issuer_did == did
        assert result.jti == "vc-jti-001"

    @pytest.mark.asyncio
    async def test_expired_vc_raises(self):
        from common.vc_engine.errors import VCError, VCErrorCode
        from common.vc_engine.resolver import DIDResolver
        from common.vc_engine.verifier import verify_vc
        priv, pub = _gen_keypair()
        did = _did_key(pub)
        vc_jwt = _make_vc_jwt(priv, pub, exp_offset=-100)  # already expired
        resolver = DIDResolver()
        with pytest.raises(VCError) as exc_info:
            await verify_vc(vc_jwt, {did}, resolver)
        assert exc_info.value.code == VCErrorCode.VC_EXPIRED

    @pytest.mark.asyncio
    async def test_nbf_future_raises(self):
        from common.vc_engine.errors import VCError, VCErrorCode
        from common.vc_engine.resolver import DIDResolver
        from common.vc_engine.verifier import verify_vc
        priv, pub = _gen_keypair()
        did = _did_key(pub)
        vc_jwt = _make_vc_jwt(priv, pub, nbf_offset=3600)  # nbf in future
        resolver = DIDResolver()
        with pytest.raises(VCError) as exc_info:
            await verify_vc(vc_jwt, {did}, resolver)
        assert exc_info.value.code == VCErrorCode.VC_NBF

    @pytest.mark.asyncio
    async def test_wrong_signature_raises(self):
        from common.vc_engine.errors import VCError, VCErrorCode
        from common.vc_engine.resolver import DIDResolver
        from common.vc_engine.verifier import verify_vc
        priv, pub = _gen_keypair()
        did = _did_key(pub)
        vc_jwt = _make_vc_jwt(priv, pub)
        # Flip a byte in the signature
        parts = vc_jwt.split(".")
        sig = list(base64.urlsafe_b64decode(parts[2] + "=="))
        sig[0] ^= 0xFF
        parts[2] = base64.urlsafe_b64encode(bytes(sig)).rstrip(b"=").decode()
        tampered = ".".join(parts)
        resolver = DIDResolver()
        with pytest.raises(VCError) as exc_info:
            await verify_vc(tampered, {did}, resolver)
        assert exc_info.value.code == VCErrorCode.SIGNATURE_INVALID

    @pytest.mark.asyncio
    async def test_untrusted_issuer_raises(self):
        from common.vc_engine.errors import VCError, VCErrorCode
        from common.vc_engine.resolver import DIDResolver
        from common.vc_engine.verifier import verify_vc
        priv, pub = _gen_keypair()
        did = _did_key(pub)
        vc_jwt = _make_vc_jwt(priv, pub)
        resolver = DIDResolver()
        with pytest.raises(VCError) as exc_info:
            # Pass empty trusted set
            await verify_vc(vc_jwt, set(), resolver)
        assert exc_info.value.code == VCErrorCode.ISSUER_UNTRUSTED

    @pytest.mark.asyncio
    async def test_revoked_vc_raises(self):
        from common.vc_engine.errors import VCError, VCErrorCode
        from common.vc_engine.resolver import DIDResolver
        from common.vc_engine.verifier import verify_vc
        priv, pub = _gen_keypair()
        did = _did_key(pub)
        extra = {"vc": {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential"],
            "credentialSubject": {"id": "did:example:subject"},
            "credentialStatus": {"statusListCredential": "list-001", "statusListIndex": 0},
        }}
        vc_jwt = _make_vc_jwt(priv, pub, extra_claims=extra)
        # Rebuilding with vc claim override
        resolver = DIDResolver()
        status_checker = AsyncMock(return_value=True)  # always revoked
        with pytest.raises(VCError) as exc_info:
            await verify_vc(vc_jwt, {did}, resolver, status_checker=status_checker)
        assert exc_info.value.code == VCErrorCode.STATUS_REVOKED

    @pytest.mark.asyncio
    async def test_schema_mismatch_raises(self):
        from common.vc_engine.errors import VCError, VCErrorCode
        from common.vc_engine.resolver import DIDResolver
        from common.vc_engine.verifier import verify_vc
        priv, pub = _gen_keypair()
        did = _did_key(pub)
        vc_jwt = _make_vc_jwt(priv, pub)
        resolver = DIDResolver()
        with pytest.raises(VCError) as exc_info:
            await verify_vc(vc_jwt, {did}, resolver, schema_validator=lambda _s: False)
        assert exc_info.value.code == VCErrorCode.SCHEMA_MISMATCH


# ---------------------------------------------------------------------------
# Test: create_vp + verify_vp round-trip
# ---------------------------------------------------------------------------

class TestCreateAndVerifyVP:
    @pytest.mark.asyncio
    async def test_create_vp_then_verify_round_trip(self):
        from common.vc_engine.builder import create_vp
        from common.vc_engine.resolver import DIDResolver
        from common.vc_engine.verifier import verify_vc, verify_vp

        priv, pub = _gen_keypair()
        did = _did_key(pub)
        vc_jwt = _make_vc_jwt(priv, pub)

        vp_jwt = create_vp(
            vcs=[vc_jwt],
            holder_did=did,
            holder_key_bytes=priv,
            aud="did:example:verifier",
            nonce="nonce-abc",
            env="prod",
        )
        resolver = DIDResolver()
        vp = await verify_vp(
            vp_jwt,
            expected_aud="did:example:verifier",
            expected_nonce="nonce-abc",
            expected_env="prod",
            resolver=resolver,
            trusted_issuer_dids={did},
        )
        assert vp.holder_did == did
        assert len(vp.vcs) == 1

    @pytest.mark.asyncio
    async def test_vp_wrong_aud_raises(self):
        from common.vc_engine.builder import create_vp
        from common.vc_engine.errors import VPError, VPErrorCode
        from common.vc_engine.resolver import DIDResolver
        from common.vc_engine.verifier import verify_vp

        priv, pub = _gen_keypair()
        did = _did_key(pub)
        vp_jwt = create_vp([], did, priv, "did:example:verifier", "nonce", "dev")
        resolver = DIDResolver()
        with pytest.raises(VPError) as exc_info:
            await verify_vp(vp_jwt, "did:example:OTHER", None, None, resolver)
        assert exc_info.value.code == VPErrorCode.VP_AUD_MISMATCH

    @pytest.mark.asyncio
    async def test_vp_wrong_nonce_raises(self):
        from common.vc_engine.builder import create_vp
        from common.vc_engine.errors import VPError, VPErrorCode
        from common.vc_engine.resolver import DIDResolver
        from common.vc_engine.verifier import verify_vp

        priv, pub = _gen_keypair()
        did = _did_key(pub)
        vp_jwt = create_vp([], did, priv, "did:example:verifier", "correct-nonce", "dev")
        resolver = DIDResolver()
        with pytest.raises(VPError) as exc_info:
            await verify_vp(vp_jwt, "did:example:verifier", "wrong-nonce", None, resolver)
        assert exc_info.value.code == VPErrorCode.VP_NONCE_MISMATCH
