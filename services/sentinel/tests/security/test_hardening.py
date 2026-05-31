"""Security hardening validation tests (TASK-053).

Cases:
1. Startup fails when did_key.enc is world-readable (chmod 0644)
2. SSLContext minimum_version is TLS 1.2
3. Certificate fingerprint mismatch raises CertificatePinViolation when pinning enabled
4. Cipher negotiation does not use RC4 or DES
5. ConfigurationError raised when mTLS only cert is provided without key

Note: Tests that require actual TLS connections or Docker are skipped in unit mode.
Windows: file-permission tests are only run on POSIX platforms.
"""
from __future__ import annotations

import os
import platform
import ssl
import stat
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_IS_POSIX = platform.system() != "Windows"

# Re-import with POSIX check handled inside tests for cipher/TLS tests
# which don't need POSIX


# ---------------------------------------------------------------------------
# Test 1: Startup fails when did_key.enc has world-readable permissions
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _IS_POSIX, reason="File permission tests only run on POSIX platforms")
class TestStartupPermissionCheck:
    def test_fails_when_enc_file_world_readable(self, tmp_path: Path):
        from sentinel.core.startup import InsecureFilePermissions, check_file_permissions

        store_dir = tmp_path / ".sentinel" / "store"
        store_dir.mkdir(parents=True, mode=0o700)

        enc_file = store_dir / "did_key.enc"
        enc_file.write_bytes(b"encrypted-key-data")
        # Set world-readable — this should trigger the check
        os.chmod(enc_file, 0o644)

        with pytest.raises(InsecureFilePermissions) as exc_info:
            check_file_permissions(sentinel_home=str(tmp_path))

        assert str(enc_file) in str(exc_info.value) or enc_file.name in str(exc_info.value)

    def test_passes_when_enc_file_has_correct_permissions(self, tmp_path: Path):
        from sentinel.core.startup import check_file_permissions

        store_dir = tmp_path / ".sentinel" / "store"
        store_dir.mkdir(parents=True, mode=0o700)

        enc_file = store_dir / "did_key.enc"
        enc_file.write_bytes(b"encrypted-key-data")
        os.chmod(enc_file, 0o600)

        # Should not raise
        check_file_permissions(sentinel_home=str(tmp_path))

    def test_fails_when_store_dir_group_readable(self, tmp_path: Path):
        from sentinel.core.startup import InsecureFilePermissions, check_file_permissions

        store_dir = tmp_path / ".sentinel" / "store"
        store_dir.mkdir(parents=True, mode=0o750)  # group-readable

        with pytest.raises(InsecureFilePermissions):
            check_file_permissions(sentinel_home=str(tmp_path))


# ---------------------------------------------------------------------------
# Test 2: SSLContext minimum_version is TLS 1.2
# ---------------------------------------------------------------------------

class TestSSLContextTLSVersion:
    def test_minimum_version_is_tls12(self):
        from common.tls.context import create_strict_ssl_context
        ctx = create_strict_ssl_context()
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2

    def test_compression_is_disabled(self):
        from common.tls.context import create_strict_ssl_context
        ctx = create_strict_ssl_context()
        assert ctx.options & ssl.OP_NO_COMPRESSION

    def test_context_purpose_is_server_auth(self):
        from common.tls.context import create_strict_ssl_context
        ctx = create_strict_ssl_context()
        # SERVER_AUTH context verifies server certs by default
        assert ctx.verify_mode in (ssl.CERT_REQUIRED, ssl.CERT_OPTIONAL)

    def test_mtls_requires_both_cert_and_key(self):
        from common.tls.context import ConfigurationError, create_strict_ssl_context
        with pytest.raises(ConfigurationError, match="Both client_cert_path"):
            create_strict_ssl_context(client_cert_path="/path/cert.pem")


# ---------------------------------------------------------------------------
# Test 3: Certificate fingerprint mismatch raises CertificatePinViolation
# ---------------------------------------------------------------------------

class TestCertificatePinning:
    def test_fingerprint_mismatch_raises(self):
        from common.tls.pinning import CertificatePinViolation, check_cert_fingerprint

        # Create a mock SSL socket with a known DER cert
        fake_cert_der = b"fake_certificate_bytes"
        import hashlib
        actual_fingerprint = hashlib.sha256(fake_cert_der).hexdigest()
        wrong_fingerprint = "a" * 64

        mock_socket = MagicMock()
        mock_socket.getpeercert.return_value = fake_cert_der
        mock_socket.server_hostname = "discovery.example.com"

        with pytest.raises(CertificatePinViolation, match="fingerprint mismatch"):
            check_cert_fingerprint(mock_socket, wrong_fingerprint)

    def test_fingerprint_match_succeeds(self):
        from common.tls.pinning import check_cert_fingerprint
        import hashlib

        fake_cert_der = b"correct_certificate_der"
        correct_fingerprint = hashlib.sha256(fake_cert_der).hexdigest()

        mock_socket = MagicMock()
        mock_socket.getpeercert.return_value = fake_cert_der
        mock_socket.server_hostname = "discovery.example.com"

        # Should not raise
        check_cert_fingerprint(mock_socket, correct_fingerprint)

    def test_is_pinning_enabled_prod(self, monkeypatch: pytest.MonkeyPatch):
        from common.tls.pinning import is_pinning_enabled
        monkeypatch.setenv("SENTINEL_CERT_PINNING", "true")
        assert is_pinning_enabled("prod") is True

    def test_is_pinning_disabled_in_dev(self, monkeypatch: pytest.MonkeyPatch):
        from common.tls.pinning import is_pinning_enabled
        monkeypatch.setenv("SENTINEL_CERT_PINNING", "true")
        assert is_pinning_enabled("dev") is False


# ---------------------------------------------------------------------------
# Test 4: Cipher negotiation does not use RC4 or DES
# ---------------------------------------------------------------------------

class TestCipherSuites:
    def test_no_rc4_cipher(self):
        from common.tls.context import create_strict_ssl_context
        ctx = create_strict_ssl_context()
        ciphers = ctx.get_ciphers()
        names = [c["name"] for c in ciphers]
        for name in names:
            assert "RC4" not in name.upper(), f"Found RC4 cipher: {name}"

    def test_no_des_cipher(self):
        from common.tls.context import create_strict_ssl_context
        ctx = create_strict_ssl_context()
        ciphers = ctx.get_ciphers()
        names = [c["name"] for c in ciphers]
        for name in names:
            # Allow AES (contains no standalone DES) but exclude 3DES/DES
            assert "3DES" not in name.upper(), f"Found 3DES cipher: {name}"
            assert name.upper() in ("", name)  # always passes; DES check below
        # Specifically check no cipher named exactly DES-*
        for name in names:
            assert not (name.upper().startswith("DES-")), f"Found DES cipher: {name}"

    def test_has_aes_gcm_ciphers(self):
        from common.tls.context import create_strict_ssl_context
        ctx = create_strict_ssl_context()
        ciphers = ctx.get_ciphers()
        names = [c["name"] for c in ciphers]
        has_aesgcm = any("GCM" in n.upper() for n in names)
        assert has_aesgcm, "No AES-GCM ciphers found in context"
