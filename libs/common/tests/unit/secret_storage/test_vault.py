"""Unit tests for VaultSecretStorage (Vault HTTP API mocked via pytest-httpx)."""

from __future__ import annotations

import base64

import httpx
import pytest
from pytest_httpx import HTTPXMock

from common.secret_storage.base import (
    SecretAccessDeniedError,
    SecretNotFoundError,
    SecretStorageCorruptedError,
    SecretStorageUnavailableError,
)
from common.secret_storage.vault import VaultSecretStorage

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VAULT_URL = "http://vault.test:8200"
ROLE_ID = "test-role-id"
SECRET_ID = "test-secret-id"
MOCK_TOKEN = "s.mock-vault-token"
MOUNT = "secret"

_LOGIN_URL = f"{VAULT_URL}/v1/auth/approle/login"
_LOGIN_RESPONSE = {
    "auth": {
        "client_token": MOCK_TOKEN,
        "lease_duration": 3600,
        "renewable": True,
    }
}


def _kv_url(key: str) -> str:
    return f"{VAULT_URL}/v1/{MOUNT}/data/{key}"


def _meta_url(key: str) -> str:
    return f"{VAULT_URL}/v1/{MOUNT}/metadata/{key}"


def _value_response(raw: bytes) -> dict:
    return {
        "data": {
            "data": {"value": base64.b64encode(raw).decode()},
            "metadata": {"version": 1},
        }
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def vault(httpx_mock: HTTPXMock) -> VaultSecretStorage:
    """Vault client with AppRole login pre-mocked."""
    httpx_mock.add_response(method="POST", url=_LOGIN_URL, json=_LOGIN_RESPONSE)
    client = httpx.AsyncClient(base_url=VAULT_URL, timeout=10.0)
    return VaultSecretStorage(
        vault_addr=VAULT_URL,
        role_id=ROLE_ID,
        secret_id=SECRET_ID,
        kv_mount=MOUNT,
        http_client=client,
    )


# ---------------------------------------------------------------------------
# GET
# ---------------------------------------------------------------------------


class TestVaultGet:
    async def test_get_success(self, vault: VaultSecretStorage, httpx_mock: HTTPXMock) -> None:
        secret = b"private-key-bytes"
        httpx_mock.add_response(method="GET", url=_kv_url("sentinels/svc/role/env/key"), json=_value_response(secret))
        result = await vault.get("sentinels/svc/role/env/key")
        assert result == secret

    async def test_get_not_found(self, vault: VaultSecretStorage, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(method="GET", url=_kv_url("sentinels/missing/key"), status_code=404)
        with pytest.raises(SecretNotFoundError) as exc_info:
            await vault.get("sentinels/missing/key")
        assert "sentinels/missing/key" in str(exc_info.value)

    async def test_get_forbidden(self, vault: VaultSecretStorage, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(method="GET", url=_kv_url("sentinels/secret/key"), status_code=403)
        with pytest.raises(SecretAccessDeniedError):
            await vault.get("sentinels/secret/key")

    async def test_get_malformed_response_raises_corrupted(
        self, vault: VaultSecretStorage, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            method="GET",
            url=_kv_url("sentinels/svc/role/env/malformed"),
            json={"data": {}},  # missing nested 'data.data.value'
        )
        with pytest.raises(SecretStorageCorruptedError):
            await vault.get("sentinels/svc/role/env/malformed")


# ---------------------------------------------------------------------------
# SET
# ---------------------------------------------------------------------------


class TestVaultSet:
    async def test_set_success(self, vault: VaultSecretStorage, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            method="POST",
            url=_kv_url("sentinels/svc/role/env/key"),
            json={"data": {"version": 1}},
        )
        await vault.set("sentinels/svc/role/env/key", b"my-secret")

    async def test_set_forbidden(self, vault: VaultSecretStorage, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            method="POST",
            url=_kv_url("sentinels/readonly/key"),
            status_code=403,
        )
        with pytest.raises(SecretAccessDeniedError):
            await vault.set("sentinels/readonly/key", b"data")


# ---------------------------------------------------------------------------
# DELETE
# ---------------------------------------------------------------------------


class TestVaultDelete:
    async def test_delete_success(self, vault: VaultSecretStorage, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(method="DELETE", url=_meta_url("sentinels/svc/role/env/key"), status_code=204)
        await vault.delete("sentinels/svc/role/env/key")

    async def test_delete_not_found_is_noop(
        self, vault: VaultSecretStorage, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(method="DELETE", url=_meta_url("sentinels/missing/key"), status_code=404)
        await vault.delete("sentinels/missing/key")  # must not raise

    async def test_delete_forbidden(self, vault: VaultSecretStorage, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(method="DELETE", url=_meta_url("sentinels/locked/key"), status_code=403)
        with pytest.raises(SecretAccessDeniedError):
            await vault.delete("sentinels/locked/key")


# ---------------------------------------------------------------------------
# EXISTS
# ---------------------------------------------------------------------------


class TestVaultExists:
    async def test_exists_true(self, vault: VaultSecretStorage, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            method="GET",
            url=_kv_url("sentinels/svc/role/env/present"),
            json=_value_response(b"some-val"),
        )
        assert await vault.exists("sentinels/svc/role/env/present") is True

    async def test_exists_false(self, vault: VaultSecretStorage, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            method="GET",
            url=_kv_url("sentinels/svc/role/env/absent"),
            status_code=404,
        )
        assert await vault.exists("sentinels/svc/role/env/absent") is False


# ---------------------------------------------------------------------------
# Network failure
# ---------------------------------------------------------------------------


async def test_connection_error_on_login_raises_unavailable(httpx_mock: HTTPXMock) -> None:
    """ConnectError during AppRole login → SecretStorageUnavailableError."""
    httpx_mock.add_exception(httpx.ConnectError("Connection refused"))
    client = httpx.AsyncClient(base_url=VAULT_URL, timeout=10.0)
    vault = VaultSecretStorage(
        vault_addr=VAULT_URL,
        role_id=ROLE_ID,
        secret_id=SECRET_ID,
        http_client=client,
    )
    with pytest.raises(SecretStorageUnavailableError):
        await vault.get("any/key")


async def test_connection_error_on_get_raises_unavailable(
    httpx_mock: HTTPXMock,
) -> None:
    """ConnectError during GET → SecretStorageUnavailableError."""
    # Successful login
    httpx_mock.add_response(method="POST", url=_LOGIN_URL, json=_LOGIN_RESPONSE)
    # Connection error on the actual GET
    httpx_mock.add_exception(httpx.ConnectError("Connection reset"))

    client = httpx.AsyncClient(base_url=VAULT_URL, timeout=10.0)
    vault = VaultSecretStorage(
        vault_addr=VAULT_URL,
        role_id=ROLE_ID,
        secret_id=SECRET_ID,
        http_client=client,
    )
    with pytest.raises(SecretStorageUnavailableError):
        await vault.get("any/key")
