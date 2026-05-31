"""Unit tests for TASK-023: Admin Authentication (OIDC/JWT) and RBAC."""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from discovery.app import create_app
from discovery.auth.local_jwt import issue_dev_token, validate_local_token
from discovery.auth.models import CurrentUser
from discovery.config import DiscoverySettings


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SECRET = "test-secret-for-unit-tests"


@pytest.fixture
def dev_settings() -> DiscoverySettings:
    return DiscoverySettings(
        database_url="postgresql+asyncpg://test:test@localhost:5432/testdb",
        env="dev",
        auth_mode="local_jwt",
        local_jwt_secret=SECRET,
    )


@pytest.fixture
def test_settings() -> DiscoverySettings:
    """Settings with env=test — dev-token endpoint should return 404."""
    return DiscoverySettings(
        database_url="postgresql+asyncpg://test:test@localhost:5432/testdb",
        env="test",
        auth_mode="local_jwt",
        local_jwt_secret=SECRET,
    )


@pytest_asyncio.fixture
async def dev_client(dev_settings):
    app = create_app(settings=dev_settings)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def test_client(test_settings):
    app = create_app(settings=test_settings)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


# ---------------------------------------------------------------------------
# local_jwt module tests
# ---------------------------------------------------------------------------

def test_issue_dev_token_returns_string():
    token = issue_dev_token("alice", ["operator"], SECRET)
    assert isinstance(token, str)
    assert len(token.split(".")) == 3  # JWT format


def test_validate_local_token_success():
    token = issue_dev_token("bob", ["security-admin"], SECRET)
    user = validate_local_token(token, SECRET)
    assert user.sub == "bob"
    assert "security-admin" in user.roles
    assert user.actor_type == "ADMIN"


def test_validate_local_token_wrong_secret():
    token = issue_dev_token("alice", ["operator"], SECRET)
    with pytest.raises(ValueError, match="TOKEN_INVALID"):
        validate_local_token(token, "wrong-secret")


def test_validate_local_token_expired():
    import time, jwt

    payload = {
        "sub": "alice",
        "roles": ["operator"],
        "actor_type": "ADMIN",
        "iat": int(time.time()) - 1000,
        "exp": int(time.time()) - 500,
        "iss": "discovery-local",
    }
    expired_token = jwt.encode(payload, SECRET, algorithm="HS256")
    with pytest.raises(ValueError, match="TOKEN_EXPIRED"):
        validate_local_token(expired_token, SECRET)


def test_break_glass_actor_type():
    token = issue_dev_token("emergency", ["security-admin"], SECRET, actor_type="BREAK_GLASS")
    user = validate_local_token(token, SECRET)
    assert user.actor_type == "BREAK_GLASS"


# ---------------------------------------------------------------------------
# Auth endpoint tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_dev_token_returns_token_in_dev_env(dev_client: AsyncClient):
    r = await dev_client.post(
        "/api/v1/auth/dev-token",
        json={"sub": "admin", "roles": ["operator"]},
    )
    assert r.status_code == 200
    data = r.json()
    assert "access_token" in data
    assert data["token_type"] == "Bearer"
    assert data["expires_in"] == 900


@pytest.mark.asyncio
async def test_dev_token_returns_404_in_test_env(test_client: AsyncClient):
    r = await test_client.post(
        "/api/v1/auth/dev-token",
        json={"sub": "admin", "roles": ["operator"]},
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_dev_token_break_glass_accepted(dev_client: AsyncClient):
    r = await dev_client.post(
        "/api/v1/auth/dev-token",
        json={"sub": "emergency", "roles": ["security-admin"], "actor_type": "BREAK_GLASS"},
    )
    assert r.status_code == 200
    # The returned token should have actor_type=BREAK_GLASS
    access_token = r.json()["access_token"]
    user = validate_local_token(access_token, SECRET)
    assert user.actor_type == "BREAK_GLASS"


# ---------------------------------------------------------------------------
# RBAC dependency tests (via a protected endpoint)
# ---------------------------------------------------------------------------
# We use the health endpoint which is unprotected, and test auth via
# a custom endpoint injected into a separate fixture app.

@pytest.fixture
def rbac_app(dev_settings):
    """App with an extra test endpoint protected by require_roles."""
    app = create_app(settings=dev_settings)

    from fastapi import Depends
    from discovery.auth.models import CurrentUser
    from discovery.auth.rbac import require_roles

    @app.get("/test/operator-only")
    async def op_only(user: CurrentUser = Depends(require_roles("operator"))):
        return {"sub": user.sub}

    @app.get("/test/security-admin-only")
    async def sa_only(user: CurrentUser = Depends(require_roles("security-admin"))):
        return {"sub": user.sub}

    return app


@pytest_asyncio.fixture
async def rbac_client(rbac_app):
    async with AsyncClient(transport=ASGITransport(app=rbac_app), base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_protected_endpoint_401_without_token(rbac_client: AsyncClient):
    r = await rbac_client.get("/test/operator-only")
    assert r.status_code == 401
    data = r.json()
    assert data["code"] == "TOKEN_MISSING"


@pytest.mark.asyncio
async def test_protected_endpoint_401_invalid_token(rbac_client: AsyncClient):
    r = await rbac_client.get(
        "/test/operator-only",
        headers={"Authorization": "Bearer not-a-real-jwt"},
    )
    assert r.status_code == 401
    data = r.json()
    assert data["code"] == "TOKEN_INVALID"


@pytest.mark.asyncio
async def test_protected_endpoint_403_wrong_role(rbac_client: AsyncClient):
    # viewer role — not operator
    token = issue_dev_token("viewer-user", ["viewer"], SECRET)
    r = await rbac_client.get(
        "/test/operator-only",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 403
    data = r.json()
    assert data["code"] == "INSUFFICIENT_ROLE"


@pytest.mark.asyncio
async def test_protected_endpoint_200_correct_role(rbac_client: AsyncClient):
    token = issue_dev_token("alice", ["operator"], SECRET)
    r = await rbac_client.get(
        "/test/operator-only",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    assert r.json()["sub"] == "alice"


@pytest.mark.asyncio
async def test_require_roles_accepts_any_matching_role(rbac_client: AsyncClient):
    # security-admin accessing operator endpoint — should fail
    token = issue_dev_token("sec_admin", ["security-admin"], SECRET)
    r = await rbac_client.get(
        "/test/operator-only",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_require_roles_correct_role_allowed(rbac_client: AsyncClient):
    token = issue_dev_token("sec_admin", ["security-admin"], SECRET)
    r = await rbac_client.get(
        "/test/security-admin-only",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# Config validator tests
# ---------------------------------------------------------------------------

def test_local_jwt_in_prod_raises():
    with pytest.raises(Exception, match="not permitted in env=prod"):
        DiscoverySettings(
            database_url="postgresql+asyncpg://x:x@localhost/db",
            env="prod",
            auth_mode="local_jwt",
        )


def test_oidc_without_issuer_url_raises():
    with pytest.raises(Exception, match="OIDC_ISSUER_URL"):
        DiscoverySettings(
            database_url="postgresql+asyncpg://x:x@localhost/db",
            env="dev",
            auth_mode="oidc",
            oidc_issuer_url="",
        )


def test_auto_approve_non_prod_in_prod_raises():
    with pytest.raises(Exception, match="auto_approve_non_prod"):
        DiscoverySettings(
            database_url="postgresql+asyncpg://x:x@localhost/db",
            env="prod",
            auth_mode="oidc",
            oidc_issuer_url="https://idp.example.com",
            auto_approve_non_prod=True,
        )
