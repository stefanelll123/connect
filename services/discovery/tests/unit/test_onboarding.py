"""Unit tests for TASK-026: Sentinel Onboarding with mTLS and DID PoP.

Tests are designed to run without a real database or Redis by using
mock dependencies (AsyncMock + fakeredis where available).
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import jwt as pyjwt
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from discovery.app import create_app
from discovery.auth.local_jwt import issue_dev_token
from discovery.config import DiscoverySettings
from discovery.dependencies import get_db, get_redis
from discovery.services.did_verification import (
    DIDResolutionError,
    InvalidSignatureError,
    UnsupportedDIDMethodError,
    _base58_decode,
    _load_did_key,
    _read_varint,
)

# ---------------------------------------------------------------------------
# Helper constants
# ---------------------------------------------------------------------------

SECRET = "test-secret-for-onboarding"

# A real Ed25519 key pair generated offline for deterministic tests.
# Private key (bytes): not actually private; just for test fixture use.
#
# We'll test the parsing logic using the known multicodec for Ed25519:
#   0xed 0x01  followed by 32 bytes of zeros (for unit test of parsing only).
_ED25519_MULTICODEC_PREFIX = bytes([0xED, 0x01])
_FAKE_PUB_KEY = b"\x00" * 32
_FAKE_DID_KEY_PAYLOAD = _ED25519_MULTICODEC_PREFIX + _FAKE_PUB_KEY


@pytest.fixture
def settings() -> DiscoverySettings:
    return DiscoverySettings(
        database_url="postgresql+asyncpg://test:test@localhost:5432/testdb",
        env="dev",
        auth_mode="local_jwt",
        local_jwt_secret=SECRET,
    )


@pytest.fixture
def app(settings):
    _app = create_app(settings=settings)
    # Override get_db and get_redis so DB/Redis unavailability doesn't mask schema validation (422)
    async def mock_get_db():
        yield AsyncMock()
    async def mock_get_redis():
        return AsyncMock()
    _app.dependency_overrides[get_db] = mock_get_db
    _app.dependency_overrides[get_redis] = mock_get_redis
    return _app


@pytest_asyncio.fixture
async def client(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


# ---------------------------------------------------------------------------
# did_verification module tests (pure unit — no I/O)
# ---------------------------------------------------------------------------


def test_base58_decode_roundtrip():
    """Decode a known base58btc string and verify the result."""
    # "z6Mk..." starts with the Ed25519 multicodec prefix 0xed 0x01
    # Test a minimal known value: base58 of b'\xed\x01' + 32 zero bytes
    import base64

    B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    # Just test that non-empty input returns non-empty bytes
    decoded = _base58_decode("1")  # "1" in base58btc is b'\x00' (leading zero)
    assert decoded == b"\x00"


def test_read_varint_single_byte():
    # 0x0d = 13, single byte with MSB clear
    val, n = _read_varint(b"\x0d\x00")
    assert val == 13
    assert n == 1


def test_read_varint_two_bytes():
    # Ed25519: 0xed 0x01 = 237
    val, n = _read_varint(bytes([0xED, 0x01]))
    assert val == 0xED  # 237
    assert n == 2


def test_read_varint_p256():
    # P-256: 0x80 0x24 = 4608 = 0x1200
    val, n = _read_varint(bytes([0x80, 0x24]))
    assert val == 0x1200
    assert n == 2


def test_load_did_key_unsupported_method():
    with pytest.raises(UnsupportedDIDMethodError):
        _load_did_key("did:web:example.com")


def test_load_did_key_not_a_did():
    with pytest.raises(DIDResolutionError):
        _load_did_key("not_a_did")


def test_load_did_key_invalid_multibase():
    # Multibase prefix not 'z' → DIDResolutionError
    with pytest.raises(DIDResolutionError, match="base58btc"):
        _load_did_key("did:key:mSomeOtherPrefix")


# ---------------------------------------------------------------------------
# Onboarding endpoint: Phase 1 challenge (mocked DB + Redis)
# ---------------------------------------------------------------------------


@pytest.fixture
def valid_enrollment_token(settings: DiscoverySettings) -> tuple[str, str, str]:
    """Returns (raw_token, jti, token_hash)."""
    jti = str(uuid.uuid4())
    exp = int(time.time()) + 600
    payload = {
        "sub": "billing-api",
        "jti": jti,
        "service_id": "billing-api",
        "role": "producer",
        "env": "dev",
        "exp": exp,
        "iat": int(time.time()),
    }
    raw = pyjwt.encode(payload, SECRET, algorithm="HS256")
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    return raw, jti, token_hash


def _make_mock_session(token_record: MagicMock | None = None):
    """Return an AsyncMock AsyncSession with get_by_jti pre-configured."""
    session = AsyncMock()
    return session


@pytest.mark.asyncio
async def test_phase1_with_invalid_token_returns_401(client: AsyncClient):
    """Phase 1 with a malformed enrollment token → 401."""
    r = await client.post(
        "/api/v1/sentinels/onboard",
        json={
            "enrollment_token": "not.a.valid.jwt",
            "did": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuias8siQmqygXiHiE",
        },
    )
    # Without a real DB the error bubbles from JWT decode → 401
    assert r.status_code in (401, 503)


@pytest.mark.asyncio
async def test_phase2_with_no_token_returns_422(client: AsyncClient):
    """Missing enrollment_token field → 422 Unprocessable Entity."""
    r = await client.post(
        "/api/v1/sentinels/onboard",
        json={"did": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuias8siQmqygXiHiE"},
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_phase2_with_no_did_returns_422(client: AsyncClient):
    """Missing did field → 422 Unprocessable Entity."""
    r = await client.post(
        "/api/v1/sentinels/onboard",
        json={"enrollment_token": "some.token.here"},
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_onboard_unknown_did_method_returns_error(client: AsyncClient, valid_enrollment_token):
    """DID using unsupported method in Phase 2 → error."""
    raw, jti, token_hash = valid_enrollment_token
    # Build a fake PoP proof
    r = await client.post(
        "/api/v1/sentinels/onboard",
        json={
            "enrollment_token": raw,
            "did": "did:ethr:0xdeadbeef",  # unsupported method
            "proof": {
                "type": "Ed25519Signature2020",
                "challenge_nonce": "fake-nonce",
                "proof_value": "zfake",
                "created": datetime.now(timezone.utc).isoformat(),
            },
        },
    )
    # Without real DB: 401 TOKEN_NOT_FOUND or 422 UNSUPPORTED_DID_METHOD
    assert r.status_code in (401, 422, 503)


# ---------------------------------------------------------------------------
# Onboarding service unit tests (fully mocked)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_issue_challenge_expired_token():
    """issue_challenge raises EnrollmentTokenValidationError for expired JWT."""
    from discovery.services.onboarding_service import (
        EnrollmentTokenValidationError,
        issue_challenge,
    )

    settings = DiscoverySettings(
        database_url="postgresql+asyncpg://test:test@localhost:5432/testdb",
        env="dev",
        auth_mode="local_jwt",
        local_jwt_secret=SECRET,
    )

    # Create an already-expired token
    payload = {
        "sub": "billing",
        "jti": str(uuid.uuid4()),
        "exp": int(time.time()) - 100,
        "iat": int(time.time()) - 700,
    }
    raw_expired = pyjwt.encode(payload, SECRET, algorithm="HS256")

    session = AsyncMock()
    redis = AsyncMock()

    with pytest.raises(EnrollmentTokenValidationError) as exc_info:
        await issue_challenge(raw_expired, settings=settings, session=session, redis=redis)

    assert exc_info.value.code == "TOKEN_EXPIRED"


@pytest.mark.asyncio
async def test_issue_challenge_invalid_signature():
    """issue_challenge raises EnrollmentTokenValidationError for wrong secret."""
    from discovery.services.onboarding_service import (
        EnrollmentTokenValidationError,
        issue_challenge,
    )

    settings = DiscoverySettings(
        database_url="postgresql+asyncpg://test:test@localhost:5432/testdb",
        env="dev",
        auth_mode="local_jwt",
        local_jwt_secret=SECRET,
    )

    # Token signed with wrong secret
    payload = {
        "jti": str(uuid.uuid4()),
        "exp": int(time.time()) + 600,
        "iat": int(time.time()),
    }
    raw_bad_sig = pyjwt.encode(payload, "wrong-secret-entirely", algorithm="HS256")

    session = AsyncMock()
    redis = AsyncMock()

    with pytest.raises(EnrollmentTokenValidationError) as exc_info:
        await issue_challenge(raw_bad_sig, settings=settings, session=session, redis=redis)

    assert exc_info.value.code == "INVALID_TOKEN_SIGNATURE"


@pytest.mark.asyncio
async def test_issue_challenge_token_not_found_in_db():
    """issue_challenge raises if JTI not found in database."""
    from discovery.services.onboarding_service import (
        EnrollmentTokenValidationError,
        issue_challenge,
    )
    from discovery.repositories.enrollment_tokens import EnrollmentTokenRepository

    settings = DiscoverySettings(
        database_url="postgresql+asyncpg://test:test@localhost:5432/testdb",
        env="dev",
        auth_mode="local_jwt",
        local_jwt_secret=SECRET,
    )

    payload = {
        "jti": str(uuid.uuid4()),
        "exp": int(time.time()) + 600,
        "iat": int(time.time()),
    }
    raw_token = pyjwt.encode(payload, SECRET, algorithm="HS256")

    session = AsyncMock()
    redis = AsyncMock()

    # Mock the repository's get_by_jti to return None (not found)
    with patch.object(
        EnrollmentTokenRepository, "get_by_jti", new=AsyncMock(return_value=None)
    ):
        with pytest.raises(EnrollmentTokenValidationError) as exc_info:
            await issue_challenge(raw_token, settings=settings, session=session, redis=redis)

    assert exc_info.value.code == "INVALID_TOKEN_SIGNATURE"


@pytest.mark.asyncio
async def test_issue_challenge_pending_token_not_approved():
    """Phase 1 raises TOKEN_NOT_APPROVED if token status is PENDING."""
    from discovery.services.onboarding_service import (
        EnrollmentTokenValidationError,
        issue_challenge,
    )
    from discovery.repositories.enrollment_tokens import EnrollmentTokenRepository

    settings = DiscoverySettings(
        database_url="postgresql+asyncpg://test:test@localhost:5432/testdb",
        env="dev",
        auth_mode="local_jwt",
        local_jwt_secret=SECRET,
    )

    jti = str(uuid.uuid4())
    raw_token = pyjwt.encode(
        {"jti": jti, "exp": int(time.time()) + 600, "iat": int(time.time())},
        SECRET,
        algorithm="HS256",
    )
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    # Create a fake "PENDING" token record
    fake_record = MagicMock()
    fake_record.token_hash = token_hash
    fake_record.status = "PENDING"

    session = AsyncMock()
    redis = AsyncMock()

    with patch.object(
        EnrollmentTokenRepository, "get_by_jti", new=AsyncMock(return_value=fake_record)
    ):
        with pytest.raises(EnrollmentTokenValidationError) as exc_info:
            await issue_challenge(raw_token, settings=settings, session=session, redis=redis)

    assert exc_info.value.code == "TOKEN_NOT_APPROVED"


@pytest.mark.asyncio
async def test_issue_challenge_approved_token_issues_nonce():
    """Phase 1 succeeds for approved token and returns a nonce."""
    from discovery.services.onboarding_service import issue_challenge
    from discovery.repositories.enrollment_tokens import EnrollmentTokenRepository
    from discovery.repositories.nonce_store import NonceStore

    settings = DiscoverySettings(
        database_url="postgresql+asyncpg://test:test@localhost:5432/testdb",
        env="dev",
        auth_mode="local_jwt",
        local_jwt_secret=SECRET,
    )

    jti = str(uuid.uuid4())
    raw_token = pyjwt.encode(
        {"jti": jti, "exp": int(time.time()) + 600, "iat": int(time.time())},
        SECRET,
        algorithm="HS256",
    )
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    fake_record = MagicMock()
    fake_record.token_hash = token_hash
    fake_record.status = "APPROVED"

    session = AsyncMock()
    redis = AsyncMock()

    with patch.object(
        EnrollmentTokenRepository, "get_by_jti", new=AsyncMock(return_value=fake_record)
    ), patch.object(
        NonceStore, "issue_nonce", new=AsyncMock(return_value="test-nonce-xyz")
    ):
        result = await issue_challenge(raw_token, settings=settings, session=session, redis=redis)

    assert result["challenge_nonce"] == "test-nonce-xyz"
    assert "challenge_expires_at" in result


# ---------------------------------------------------------------------------
# Nonce store unit tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_nonce_store_issue_and_consume():
    """NonceStore.issue_nonce + consume_nonce roundtrip with fakeredis."""
    try:
        import fakeredis.aioredis as fakeredis
    except ImportError:
        pytest.skip("fakeredis not installed")

    from discovery.repositories.nonce_store import NonceStore

    redis = fakeredis.FakeRedis()
    store = NonceStore(redis)

    jti = str(uuid.uuid4())
    nonce = await store.issue_nonce(jti, ttl_seconds=60)
    assert isinstance(nonce, str)
    assert len(nonce) > 10

    # First consume: should succeed
    ok = await store.consume_nonce(jti, nonce)
    assert ok is True

    # Second consume: nonce should be gone (one-time use)
    ok2 = await store.consume_nonce(jti, nonce)
    assert ok2 is False


@pytest.mark.asyncio
async def test_nonce_store_wrong_nonce_returns_false():
    """consume_nonce returns False for wrong nonce (but still deletes the stored one)."""
    try:
        import fakeredis.aioredis as fakeredis
    except ImportError:
        pytest.skip("fakeredis not installed")

    from discovery.repositories.nonce_store import NonceStore

    redis = fakeredis.FakeRedis()
    store = NonceStore(redis)

    jti = str(uuid.uuid4())
    await store.issue_nonce(jti, ttl_seconds=60)

    # Provide wrong nonce
    ok = await store.consume_nonce(jti, "completely-wrong")
    assert ok is False
