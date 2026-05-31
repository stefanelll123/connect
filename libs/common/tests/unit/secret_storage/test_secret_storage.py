"""Unit tests for common.secret_storage — LocalKeyBackend and VaultKeyBackend."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from common.secret_storage.backend import KeyBackend, KeyMaterial
from common.secret_storage.local_backend import LocalKeyBackend
from common.secret_storage.vault_backend import VaultKeyBackend

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _gen_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def _make_material(service_id: str = "svc", role: str = "PRODUCER", env: str = "dev") -> KeyMaterial:
    return KeyMaterial(
        private_key=_gen_key(),
        service_id=service_id,
        role=role,
        env=env,
        key_version=1,
    )


# ---------------------------------------------------------------------------
# TestKeyMaterial
# ---------------------------------------------------------------------------


class TestKeyMaterial:
    def test_fields(self) -> None:
        km = _make_material()
        assert km.service_id == "svc"
        assert km.role == "PRODUCER"
        assert km.env == "dev"
        assert km.key_version == 1
        assert isinstance(km.private_key, Ed25519PrivateKey)

    def test_default_key_version(self) -> None:
        km = KeyMaterial(private_key=_gen_key(), service_id="a", role="PRODUCER", env="dev")
        assert km.key_version == 1


# ---------------------------------------------------------------------------
# TestKeyBackendProtocol
# ---------------------------------------------------------------------------


class TestKeyBackendProtocol:
    def test_local_backend_satisfies_protocol(self, tmp_path: Path) -> None:
        backend = LocalKeyBackend(tmp_path, password="secret")
        assert isinstance(backend, KeyBackend)

    def test_vault_backend_satisfies_protocol(self) -> None:
        backend = VaultKeyBackend(vault_url="http://vault:8200", token="tok")
        assert isinstance(backend, KeyBackend)


# ---------------------------------------------------------------------------
# TestLocalKeyBackend
# ---------------------------------------------------------------------------


class TestLocalKeyBackend:
    # --- has_key ---

    def test_has_key_false_when_no_file(self, tmp_path: Path) -> None:
        backend = LocalKeyBackend(tmp_path, password="pass")
        assert backend.has_key("svc", "PRODUCER", "dev") is False

    def test_has_key_true_after_write(self, tmp_path: Path) -> None:
        backend = LocalKeyBackend(tmp_path, password="pass")
        material = _make_material()
        backend.write_key(material)
        assert backend.has_key("svc", "PRODUCER", "dev") is True

    # --- write and read roundtrip ---

    def test_roundtrip_preserves_private_key_bytes(self, tmp_path: Path) -> None:
        backend = LocalKeyBackend(tmp_path, password="secret-password")
        original = _make_material(service_id="testsvc", role="CONSUMER", env="prod")
        backend.write_key(original)

        loaded = backend.read_key("testsvc", "CONSUMER", "prod")
        assert loaded.private_key.private_bytes_raw() == original.private_key.private_bytes_raw()

    def test_roundtrip_preserves_metadata(self, tmp_path: Path) -> None:
        backend = LocalKeyBackend(tmp_path, password="pw")
        material = KeyMaterial(
            private_key=_gen_key(),
            service_id="my-service",
            role="PRODUCER",
            env="test",
            key_version=3,
        )
        backend.write_key(material)
        loaded = backend.read_key("my-service", "PRODUCER", "test")
        assert loaded.service_id == "my-service"
        assert loaded.role == "PRODUCER"
        assert loaded.env == "test"
        assert loaded.key_version == 3

    # --- wrong password ---

    def test_wrong_password_raises_value_error(self, tmp_path: Path) -> None:
        writer = LocalKeyBackend(tmp_path, password="correct-password")
        writer.write_key(_make_material())

        reader = LocalKeyBackend(tmp_path, password="wrong-password")
        with pytest.raises(ValueError, match="authentication tag mismatch|Failed to decrypt"):
            reader.read_key("svc", "PRODUCER", "dev")

    # --- missing file ---

    def test_read_missing_file_raises_key_error(self, tmp_path: Path) -> None:
        backend = LocalKeyBackend(tmp_path, password="pw")
        with pytest.raises(KeyError, match="No key file found"):
            backend.read_key("svc", "PRODUCER", "dev")

    # --- identity mismatch (corrupt file copied to wrong path) ---

    def test_identity_mismatch_raises_value_error(self, tmp_path: Path) -> None:
        backend = LocalKeyBackend(tmp_path, password="pw")
        material = KeyMaterial(
            private_key=_gen_key(),
            service_id="svc-a",
            role="PRODUCER",
            env="dev",
        )
        backend.write_key(material)

        # Manually rename the file to pretend it belongs to svc-b
        src = list((tmp_path / "keys").iterdir())[0]
        dest = src.parent / "svc-b-PRODUCER-dev.key.enc"
        src.rename(dest)

        # The stored identity (svc-a) differs from the requested identity (svc-b)
        with pytest.raises(ValueError, match="identity mismatch"):
            backend.read_key("svc-b", "PRODUCER", "dev")

    # --- corrupt file (invalid JSON) ---

    def test_corrupt_json_raises_value_error(self, tmp_path: Path) -> None:
        backend = LocalKeyBackend(tmp_path, password="pw")
        backend.write_key(_make_material())
        path = next((tmp_path / "keys").iterdir())
        path.write_text("{ invalid json }", encoding="utf-8")
        with pytest.raises(ValueError, match="not valid JSON"):
            backend.read_key("svc", "PRODUCER", "dev")

    # --- multiple distinct keys ---

    def test_multiple_keys_independent(self, tmp_path: Path) -> None:
        backend = LocalKeyBackend(tmp_path, password="pw")
        m1 = KeyMaterial(private_key=_gen_key(), service_id="svc", role="PRODUCER", env="dev")
        m2 = KeyMaterial(private_key=_gen_key(), service_id="svc", role="CONSUMER", env="dev")
        backend.write_key(m1)
        backend.write_key(m2)
        l1 = backend.read_key("svc", "PRODUCER", "dev")
        l2 = backend.read_key("svc", "CONSUMER", "dev")
        assert l1.private_key.private_bytes_raw() != l2.private_key.private_bytes_raw()

    # --- bytes password works too ---

    def test_bytes_password(self, tmp_path: Path) -> None:
        pw = b"raw-bytes-password"
        backend = LocalKeyBackend(tmp_path, password=pw)
        material = _make_material()
        backend.write_key(material)
        loaded = backend.read_key("svc", "PRODUCER", "dev")
        assert loaded.private_key.private_bytes_raw() == material.private_key.private_bytes_raw()

    # --- file is deterministically different each write (random salt/nonce) ---

    def test_each_write_produces_different_ciphertext(self, tmp_path: Path) -> None:
        backend = LocalKeyBackend(tmp_path, password="pw")
        material = _make_material()
        backend.write_key(material)
        path = next((tmp_path / "keys").iterdir())
        first_content = path.read_text()
        backend.write_key(material)  # overwrite
        second_content = path.read_text()
        first_ct = json.loads(first_content)["ciphertext"]
        second_ct = json.loads(second_content)["ciphertext"]
        assert first_ct != second_ct  # different nonce → different ciphertext


# ---------------------------------------------------------------------------
# TestVaultKeyBackend
# ---------------------------------------------------------------------------


def _mock_response(status_code: int, json_data: dict | None = None) -> MagicMock:
    """Build a mock httpx.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    resp.text = str(json_data)
    return resp


class TestVaultKeyBackend:
    """Uses a mock httpx.Client injected via the http_client parameter."""

    def _backend(self, client: MagicMock) -> VaultKeyBackend:
        return VaultKeyBackend(
            vault_url="http://vault:8200",
            token="test-token",
            kv_mount="secret",
            http_client=client,
        )

    # --- has_key ---

    def test_has_key_true_on_200(self) -> None:
        client = MagicMock()
        client.head.return_value = _mock_response(200)
        assert self._backend(client).has_key("svc", "PRODUCER", "dev") is True

    def test_has_key_false_on_404(self) -> None:
        client = MagicMock()
        client.head.return_value = _mock_response(404)
        assert self._backend(client).has_key("svc", "PRODUCER", "dev") is False

    def test_has_key_false_on_http_error(self) -> None:
        import httpx

        client = MagicMock()
        client.head.side_effect = httpx.ConnectError("unreachable")
        assert self._backend(client).has_key("svc", "PRODUCER", "dev") is False

    # --- read_key ---

    def test_read_key_success(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        key_hex = private_key.private_bytes_raw().hex()
        payload = {"data": {"data": {"private_key_hex": key_hex, "key_version": 2}}}
        client = MagicMock()
        client.get.return_value = _mock_response(200, payload)

        loaded = self._backend(client).read_key("svc", "PRODUCER", "dev")
        assert loaded.private_key.private_bytes_raw() == private_key.private_bytes_raw()
        assert loaded.key_version == 2
        assert loaded.service_id == "svc"

    def test_read_key_404_raises_key_error(self) -> None:
        client = MagicMock()
        client.get.return_value = _mock_response(404)
        with pytest.raises(KeyError, match="not found"):
            self._backend(client).read_key("svc", "PRODUCER", "dev")

    def test_read_key_500_raises_runtime_error(self) -> None:
        client = MagicMock()
        client.get.return_value = _mock_response(500)
        with pytest.raises(RuntimeError, match="500"):
            self._backend(client).read_key("svc", "PRODUCER", "dev")

    def test_read_key_malformed_json_raises_value_error(self) -> None:
        client = MagicMock()
        client.get.return_value = _mock_response(200, {"data": {}})  # missing inner 'data'
        with pytest.raises(ValueError, match="Malformed secret"):
            self._backend(client).read_key("svc", "PRODUCER", "dev")

    def test_read_key_network_error_raises_runtime_error(self) -> None:
        import httpx

        client = MagicMock()
        client.get.side_effect = httpx.ConnectError("timeout")
        with pytest.raises(RuntimeError, match="Vault HTTP error"):
            self._backend(client).read_key("svc", "PRODUCER", "dev")

    # --- write_key ---

    def test_write_key_success_200(self) -> None:
        client = MagicMock()
        client.post.return_value = _mock_response(200)
        material = _make_material()
        self._backend(client).write_key(material)

        args, kwargs = client.post.call_args
        assert "sentinels/svc/PRODUCER/dev" in args[0]
        body = kwargs["json"]
        assert "private_key_hex" in body["data"]

    def test_write_key_success_204(self) -> None:
        client = MagicMock()
        client.post.return_value = _mock_response(204)
        self._backend(client).write_key(_make_material())  # should not raise

    def test_write_key_403_raises_runtime_error(self) -> None:
        client = MagicMock()
        client.post.return_value = _mock_response(403)
        with pytest.raises(RuntimeError, match="403"):
            self._backend(client).write_key(_make_material())

    def test_write_key_network_error_raises_runtime_error(self) -> None:
        import httpx

        client = MagicMock()
        client.post.side_effect = httpx.ConnectError("timeout")
        with pytest.raises(RuntimeError, match="Vault HTTP error"):
            self._backend(client).write_key(_make_material())

    # --- path construction ---

    def test_correct_vault_path_in_request(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        payload = {
            "data": {
                "data": {
                    "private_key_hex": private_key.private_bytes_raw().hex(),
                    "key_version": 1,
                }
            }
        }
        client = MagicMock()
        client.get.return_value = _mock_response(200, payload)
        self._backend(client).read_key("my-svc", "CONSUMER", "prod")

        called_url = client.get.call_args[0][0]
        assert "sentinels/my-svc/CONSUMER/prod/did_private_key" in called_url
        assert "secret/data" in called_url

    def test_token_header_sent(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        payload = {
            "data": {
                "data": {
                    "private_key_hex": private_key.private_bytes_raw().hex(),
                }
            }
        }
        client = MagicMock()
        client.get.return_value = _mock_response(200, payload)
        backend = VaultKeyBackend(
            vault_url="http://vault:8200", token="my-secret-tok", http_client=client
        )
        backend.read_key("svc", "PRODUCER", "dev")
        headers = client.get.call_args[1]["headers"]
        assert headers["X-Vault-Token"] == "my-secret-tok"
