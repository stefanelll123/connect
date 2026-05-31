"""Unit tests for TASK-038: Sentinel Wallet and Key Storage."""
from __future__ import annotations

import base64
import json
import os
import platform
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# SecretBytes
# ---------------------------------------------------------------------------

class TestSecretBytes:
    def test_reveal_returns_original_bytes(self):
        from sentinel.wallet.secret_bytes import SecretBytes
        data = b"super-secret-key-material-12345"
        sb = SecretBytes(data)
        assert sb.reveal() == data

    def test_repr_does_not_expose_data(self):
        from sentinel.wallet.secret_bytes import SecretBytes
        sb = SecretBytes(b"sensitive")
        assert "sensitive" not in repr(sb)
        assert repr(sb) == "<secret>"

    def test_str_does_not_expose_data(self):
        from sentinel.wallet.secret_bytes import SecretBytes
        sb = SecretBytes(b"sensitive")
        assert str(sb) == "<secret>"

    def test_len_returns_correct_length(self):
        from sentinel.wallet.secret_bytes import SecretBytes
        data = b"1234567890"
        sb = SecretBytes(data)
        assert len(sb) == 10

    def test_equality_constant_time(self):
        from sentinel.wallet.secret_bytes import SecretBytes
        a = SecretBytes(b"same-key")
        b = SecretBytes(b"same-key")
        c = SecretBytes(b"diff-key")
        assert a == b
        assert a != c

    def test_not_hashable(self):
        from sentinel.wallet.secret_bytes import SecretBytes
        sb = SecretBytes(b"data")
        with pytest.raises(TypeError):
            hash(sb)

    def test_not_picklable(self):
        from sentinel.wallet.secret_bytes import SecretBytes
        import pickle
        sb = SecretBytes(b"data")
        with pytest.raises(TypeError):
            pickle.dumps(sb)

    def test_not_json_serialisable(self):
        from sentinel.wallet.secret_bytes import SecretBytes
        sb = SecretBytes(b"data")
        with pytest.raises(TypeError):
            json.dumps(sb)

    def test_requires_bytes_input(self):
        from sentinel.wallet.secret_bytes import SecretBytes
        with pytest.raises(TypeError):
            SecretBytes("string-not-bytes")  # type: ignore

    def test_zero_on_del(self):
        """After deletion the buffer should be zeroed."""
        from sentinel.wallet.secret_bytes import SecretBytes
        import ctypes, gc
        data = b"\xAA" * 32
        sb = SecretBytes(data)
        buf_ptr = sb._buf  # keep a reference to the ctypes buffer
        del sb
        gc.collect()
        # Check that the underlying memory is zeroed
        assert bytes(buf_ptr.raw) == b"\x00" * 32


# ---------------------------------------------------------------------------
# CredentialStore
# ---------------------------------------------------------------------------

def _make_jwt(jti: str, cred_type: str = "VerifiableCredential", exp: int = None) -> str:
    """Build a minimal unsigned JWT for testing."""
    header = {"alg": "none", "typ": "JWT"}
    payload = {
        "jti": jti,
        "type": cred_type,
        "iss": "did:example:issuer",
        "exp": exp or int(time.time()) + 3600,
    }
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{h}.{p}."


class TestCredentialStore:
    def test_store_and_retrieve_active(self, tmp_path):
        from sentinel.wallet.credential_store import CredentialStore
        store = CredentialStore(tmp_path)
        master_key = os.urandom(32)
        jwt = _make_jwt(jti="abc-1234-5678")
        store.store(jwt, master_key=master_key)
        active = store.get_active("VerifiableCredential", master_key=master_key)
        assert len(active) == 1
        assert active[0] == jwt

    def test_expired_credentials_excluded(self, tmp_path):
        from sentinel.wallet.credential_store import CredentialStore
        store = CredentialStore(tmp_path)
        master_key = os.urandom(32)
        expired_jwt = _make_jwt(jti="exp-0001", exp=int(time.time()) - 100)
        store.store(expired_jwt, master_key=master_key)
        active = store.get_active("VerifiableCredential", master_key=master_key, now=time.time())
        assert len(active) == 0

    def test_invalidate_removes_file(self, tmp_path):
        from sentinel.wallet.credential_store import CredentialStore
        store = CredentialStore(tmp_path)
        master_key = os.urandom(32)
        jwt = _make_jwt(jti="del-9999")
        store.store(jwt, master_key=master_key)
        store.invalidate("del-9999")
        active = store.get_active("VerifiableCredential", master_key=master_key)
        assert len(active) == 0

    def test_wrong_key_returns_no_credentials(self, tmp_path):
        from sentinel.wallet.credential_store import CredentialStore
        store = CredentialStore(tmp_path)
        master_key = os.urandom(32)
        wrong_key = os.urandom(32)
        jwt = _make_jwt(jti="wrong-key-test")
        store.store(jwt, master_key=master_key)
        # get_active with wrong key should silently skip corrupted data
        active = store.get_active("VerifiableCredential", master_key=wrong_key)
        assert len(active) == 0

    def test_multiple_credentials_stored_and_retrieved(self, tmp_path):
        from sentinel.wallet.credential_store import CredentialStore
        store = CredentialStore(tmp_path)
        master_key = os.urandom(32)
        for i in range(3):
            store.store(_make_jwt(jti=f"multi-{i:04d}"), master_key=master_key)
        active = store.get_active("VerifiableCredential", master_key=master_key)
        assert len(active) == 3

    def test_secret_bytes_master_key_accepted(self, tmp_path):
        from sentinel.wallet.credential_store import CredentialStore
        from sentinel.wallet.secret_bytes import SecretBytes
        store = CredentialStore(tmp_path)
        raw = os.urandom(32)
        master_key = SecretBytes(raw)
        jwt = _make_jwt(jti="sb-key-test")
        store.store(jwt, master_key=master_key)
        active = store.get_active("VerifiableCredential", master_key=master_key)
        assert len(active) == 1


# ---------------------------------------------------------------------------
# StatusCache
# ---------------------------------------------------------------------------

class TestStatusCache:
    def test_put_and_get(self, tmp_path):
        from sentinel.wallet.status_cache import StatusCache
        cache = StatusCache(tmp_path)
        data = b"bitstring-status-list-data"
        cache.put("list-001", data, expires_at=time.time() + 3600)
        result = cache.get("list-001")
        assert result == data

    def test_missing_returns_none(self, tmp_path):
        from sentinel.wallet.status_cache import StatusCache
        cache = StatusCache(tmp_path)
        assert cache.get("nonexistent") is None

    def test_is_stale_when_expired(self, tmp_path):
        from sentinel.wallet.status_cache import StatusCache
        cache = StatusCache(tmp_path)
        cache.put("list-002", b"data", expires_at=time.time() - 1)
        assert cache.is_stale("list-002") is True

    def test_is_not_stale_when_fresh(self, tmp_path):
        from sentinel.wallet.status_cache import StatusCache
        cache = StatusCache(tmp_path)
        cache.put("list-003", b"data", expires_at=time.time() + 3600)
        assert cache.is_stale("list-003") is False

    def test_is_stale_when_missing(self, tmp_path):
        from sentinel.wallet.status_cache import StatusCache
        cache = StatusCache(tmp_path)
        assert cache.is_stale("no-such-list") is True

    def test_corrupted_bin_returns_none(self, tmp_path):
        from sentinel.wallet.status_cache import StatusCache
        import json as _json
        cache = StatusCache(tmp_path)
        data = b"original"
        cache.put("list-corrupt", data, expires_at=time.time() + 3600)
        # Corrupt the .bin file
        (tmp_path / "list-corrupt.bin").write_bytes(b"garbage-data-here")
        result = cache.get("list-corrupt")
        assert result is None

    def test_evict_removes_files(self, tmp_path):
        from sentinel.wallet.status_cache import StatusCache
        cache = StatusCache(tmp_path)
        cache.put("list-del", b"data", expires_at=time.time() + 3600)
        cache.evict("list-del")
        assert cache.get("list-del") is None
        assert not (tmp_path / "list-del.bin").exists()
        assert not (tmp_path / "list-del_meta.json").exists()

    def test_special_chars_in_id_are_sanitised(self, tmp_path):
        from sentinel.wallet.status_cache import StatusCache
        cache = StatusCache(tmp_path)
        # IDs with slashes/dots should be stored safely
        cache.put("https://example.com/status/list-1", b"data", expires_at=time.time() + 3600)
        result = cache.get("https://example.com/status/list-1")
        assert result == b"data"


# ---------------------------------------------------------------------------
# Permission checks
# ---------------------------------------------------------------------------

@pytest.mark.skipif(platform.system() == "Windows", reason="UNIX permissions not enforced on Windows")
class TestPermissionCheck:
    def test_correct_permissions_pass(self, tmp_path):
        from sentinel.startup.permission_check import check_store_permissions
        os.chmod(tmp_path, 0o700)
        # Should not raise
        check_store_permissions(tmp_path)

    def test_wrong_dir_permissions_raise(self, tmp_path):
        from sentinel.startup.permission_check import check_store_permissions, StartupPermissionError
        os.chmod(tmp_path, 0o755)  # too permissive
        with pytest.raises(StartupPermissionError, match="Insecure permissions"):
            check_store_permissions(tmp_path)

    def test_wrong_file_permissions_raise(self, tmp_path):
        from sentinel.startup.permission_check import check_store_permissions, StartupPermissionError
        os.chmod(tmp_path, 0o700)
        key_file = tmp_path / "test.enc"
        key_file.write_bytes(b"encrypted")
        os.chmod(key_file, 0o644)  # too permissive
        with pytest.raises(StartupPermissionError, match="Insecure permissions"):
            check_store_permissions(tmp_path)

    def test_correct_file_permissions_pass(self, tmp_path):
        from sentinel.startup.permission_check import check_store_permissions
        os.chmod(tmp_path, 0o700)
        key_file = tmp_path / "test.enc"
        key_file.write_bytes(b"encrypted")
        os.chmod(key_file, 0o600)
        check_store_permissions(tmp_path)

    def test_root_process_raises(self, tmp_path):
        from sentinel.startup.permission_check import check_store_permissions, StartupPermissionError
        os.chmod(tmp_path, 0o700)
        with patch("os.getuid", return_value=0):
            with pytest.raises(StartupPermissionError, match="root"):
                check_store_permissions(tmp_path)


class TestPermissionCheckWindows:
    """On Windows, check_store_permissions should be a no-op."""
    def test_windows_noop(self, tmp_path):
        from sentinel.startup.permission_check import check_store_permissions
        with patch("platform.system", return_value="Windows"):
            # Must not raise regardless of permissions
            check_store_permissions(tmp_path)
